"""Turn measurements into a verdict, and make the verdict explain itself.

The scoring pieces each answer one question -- how vulnerable, how hardened,
how much surface, how trustworthy is the evidence. This is where they are
put together into what the user actually asked for: *should I run this*, and
*why did it beat the alternative*.

Two rules govern the composition, and both exist because the obvious
alternative is wrong:

**Hardening never offsets vulnerabilities.** The dimensions are reported
side by side and are never summed. A perfectly configured image carrying an
unfixable CRITICAL is a perfectly configured vulnerable image, and the
production-ready verdict it gets is the one its CVEs earn. `SecurityTier`
already enforces the ceiling; nothing here may route around it.

**Confidence is a gate, not a decoration.** An UNVERIFIED candidate is not a
low-scoring candidate: it is one about which nothing is known, and the
ranking refuses to place it above anything that was actually measured.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.application.services.cross_validation import CrossValidationOutcome
from dockerls.domain.value_objects.attack_surface import AttackSurfaceScore
from dockerls.domain.value_objects.confidence import (
    Confidence,
    ConfidenceAssessment,
    ConfidenceInputs,
    confidence_rank,
)
from dockerls.domain.value_objects.hardening import HardeningScore
from dockerls.domain.value_objects.production_readiness import (
    ProductionReadiness,
    ReadinessInputs,
)
from dockerls.domain.value_objects.security_tier import Tier
from dockerls.domain.value_objects.tristate import Tristate

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ImageAnalysis
    from dockerls.domain.entities.image_facts import HardeningFacts

from dockerls.application.dto.analysis import DimensionReport


def apply_facts(analysis: ImageAnalysis, facts: HardeningFacts) -> None:
    """Attach an evidence record and the two dimensions derived from it.

    In-place, matching how `CrossValidator` annotates an analysis: the
    pipeline enriches one object as evidence arrives rather than rebuilding
    it at each stage.
    """
    hardening = HardeningScore(facts)
    surface = AttackSurfaceScore(facts)

    analysis.facts = facts
    analysis.hardening = DimensionReport(
        score=hardening.value,
        coverage=hardening.coverage,
        reportable=hardening.is_reportable,
        positives=hardening.strengths,
        negatives=hardening.weaknesses,
        undetermined=hardening.undetermined,
    )
    analysis.attack_surface = DimensionReport(
        score=surface.value,
        coverage=surface.coverage,
        reportable=surface.is_reportable,
        # Inverted relative to hardening on purpose: for surface, the
        # elements *present* are what count against the image.
        positives=surface.absent,
        negatives=surface.present,
        undetermined=[item.name for item in surface.items if not item.determined],
    )


def finalize_verdict(analysis: ImageAnalysis, *, cross_validated: bool) -> None:
    """Set confidence and the explanation, once all evidence is in.

    Called after tag verification and cross-validation, because both feed
    the confidence assessment: computing it earlier would report a
    confidence that ignores the checks still to come.
    """
    assessment = ConfidenceAssessment(
        ConfidenceInputs(
            scan_verified=analysis.scan.is_verified,
            cross_validated=cross_validated,
            scanners_disagree=bool(analysis.scan_divergence),
            scanners_differ_slightly=(
                analysis.cross_validation == CrossValidationOutcome.MINOR_DIVERGENCE.value
            ),
            digest_resolved=analysis.image.digest_known,
            registry_verified=analysis.hub_tag_verified,
            hardening_coverage=analysis.hardening.coverage,
        )
    )
    analysis.confidence = assessment.level
    analysis.confidence_reasons = assessment.reasons

    # Production readiness is decided here, not by the tier, and not before
    # the evidence is in. `SecurityTier.production_ready` can only see the
    # score, so a PARTIAL scan with no findings in the targets it managed to
    # read produced tier A and "production ready" on the same analysis that
    # reported UNVERIFIED. The policy below is the only thing that writes
    # this field.
    readiness = ProductionReadiness.evaluate(
        ReadinessInputs(
            tier=Tier(analysis.tier),
            confidence=analysis.confidence,
            scan_verified=analysis.scan.is_verified,
            eol=analysis.eol_status,
            critical_count=analysis.scan.critical_count,
            high_count=analysis.scan.high_count,
            unfixable_critical_count=(
                analysis.scan.critical_count - analysis.scan.fixable_critical_count
            ),
            has_material_divergence=bool(analysis.scan_divergence),
        )
    )
    analysis.production_ready = readiness.is_ready
    analysis.readiness_blockers = readiness.codes
    analysis.readiness_reasons = readiness.reasons

    analysis.why = _why(analysis)
    analysis.trade_offs = _trade_offs(analysis)


def ranking_key(analysis: ImageAnalysis) -> tuple[float, ...]:
    """Total ordering across sources, best first under `reverse=True`.

    The order of the terms *is* the policy, so it is stated here once and
    read the same way by `recommend`, `alternatives` and the advisor:

    1. **confidence** -- an unverified candidate never outranks a measured
       one, whatever its numbers say;
    2. **security score** -- the measured vulnerability position, which is
       what the whole exercise is about;
    3. **hardening**, but only when enough of it was determined to mean
       something; a thin-coverage 100 must not beat a fully-inspected 85;
    4. **attack surface**, negated so less surface ranks higher;
    5. **remediation score** -- between two equivalent images, prefer the
       one whose findings can actually be fixed.

    Hardening enters only after the vulnerability position, which is the
    structural reason it can never mask a CRITICAL: no value of terms 3-5
    can move a candidate past a difference in term 2.
    """
    return (
        float(confidence_rank(analysis.confidence)),
        analysis.security_score,
        analysis.hardening.score if analysis.hardening.reportable else 0.0,
        -(analysis.attack_surface.score if analysis.attack_surface.reportable else 0.0),
        float(analysis.remediation_score),
    )


def rank(analyses: list[ImageAnalysis]) -> list[ImageAnalysis]:
    """Order candidates from every source under one comparable policy."""
    return sorted(analyses, key=lambda analysis: ranking_key(analysis), reverse=True)


def _why(analysis: ImageAnalysis) -> list[str]:
    """The case for this image, in facts a reader can check.

    Only statements backed by something that was actually determined get in.
    "No critical vulnerabilities" is earned by a completed scan; "runs as
    non-root" is earned by a config that was read or a declaration that was
    made, and the phrasing says which.
    """
    scan = analysis.scan
    reasons: list[str] = []

    if scan.critical_count == 0:
        reasons.append("no CRITICAL vulnerabilities")
    if scan.high_count == 0:
        reasons.append("no HIGH vulnerabilities")
    # "No known-exploited vulnerabilities" is the strongest claim this tool
    # makes about real-world exploitation, and it may only be made when the
    # KEV catalogue actually answered. With the feed unreachable every CVE
    # comes back `exploit_known=False`, and stating the claim on that basis
    # would be reporting a failed lookup as a security property.
    #
    # A CVE the catalogue *does* list is the mirror case, and it belongs in
    # `_trade_offs`, not here: it used to land in this list, so a log4j RCE
    # under active exploitation (CVE-2021-44228, CISA KEV) printed as a `+`
    # reason to pick the image. Exploitation observed in the wild is never a
    # point in an image's favour.
    checked = [v for v in scan.vulnerabilities if v.kev_status.is_known]
    if checked and not any(v.exploit_known for v in checked):
        reasons.append(
            f"no known-exploited (CISA KEV) vulnerabilities among the "
            f"{len(checked)} finding(s) checked"
        )
    if analysis.eol_status.is_false:
        reasons.append("not end-of-life")
    if analysis.is_lts:
        reasons.append("long-term-support release")

    facts = analysis.facts
    if facts.runs_as_non_root.is_true:
        reasons.append(f"runs as a non-root account ({facts.source_of('runs_as_non_root').value})")
    if analysis.hardening.reportable:
        reasons.extend(analysis.hardening.positives)
    if analysis.attack_surface.reportable and analysis.attack_surface.positives:
        reasons.extend(analysis.attack_surface.positives)

    if analysis.image.digest_known:
        reasons.append("pinned to a resolved manifest digest")
    if analysis.hub_tag_verified is True:
        reasons.append("tag confirmed in its source registry")
    if cross_validation_agreed(analysis):
        reasons.append("two scanners agreed on the vulnerability counts")

    return _deduplicate(reasons)


def cross_validation_agreed(analysis: ImageAnalysis) -> bool:
    """A second scanner ran and did not disagree materially.

    Distinguished from "no second scanner ran": the evidence path for the
    secondary scanner is what proves one did.
    """
    if analysis.cross_validation == CrossValidationOutcome.AGREEMENT.value:
        return True
    # Fall back to the older signal for analyses produced before the outcome
    # was recorded (a cache entry, a hand-built DTO): two evidence files and
    # no material dispute is what "agreed" used to mean.
    scanners = set(analysis.evidence_paths)
    return len(scanners) > 1 and not analysis.scan_divergence


def _trade_offs(analysis: ImageAnalysis) -> list[str]:
    """What this image costs, stated next to what it offers."""
    costs: list[str] = []
    scan = analysis.scan

    if scan.critical_count:
        costs.append(f"{scan.critical_count} CRITICAL vulnerability(ies) present")
    if scan.high_count:
        costs.append(f"{scan.high_count} HIGH vulnerability(ies) present")
    if analysis.eol_status.is_true:
        costs.append("this release is end-of-life and will not receive security fixes")
    elif analysis.eol_status is Tristate.UNKNOWN:
        costs.append(
            "end-of-life status could not be determined: this is not a statement that "
            "the release is supported"
        )
    if analysis.scan.total_count and not any(
        v.kev_status.is_known for v in analysis.scan.vulnerabilities
    ):
        costs.append("exploitation status (CISA KEV) could not be determined for any finding")
    exploited = sum(1 for v in scan.vulnerabilities if v.exploit_known)
    if exploited:
        costs.append(f"{exploited} known-exploited (CISA KEV) vulnerability(ies) present")
    if analysis.scan_divergence:
        costs.append(f"scanners disagree: {analysis.scan_divergence}")
    if analysis.confidence is not Confidence.HIGH:
        costs.extend(analysis.confidence_reasons)

    facts = analysis.facts
    if facts.runs_as_non_root.is_false:
        costs.append("runs as root by default")
    if analysis.hardening.reportable:
        costs.extend(analysis.hardening.negatives)
    if analysis.attack_surface.reportable:
        costs.extend(analysis.attack_surface.negatives)
    costs.extend(facts.conflicts)

    if not analysis.image.digest_known:
        costs.append("no manifest digest resolved: the tag may move under you")
    declared = analysis.image.declared
    if declared is not None and declared.is_dev_variant:
        costs.append(
            f"this is the '{declared.variant}' variant, which ships build tooling by design"
        )
    if facts.has_shell is Tristate.UNKNOWN and facts.has_package_manager is Tristate.UNKNOWN:
        costs.append("image contents could not be inspected: shell and package manager unknown")

    return _deduplicate(costs)


def _deduplicate(items: list[str]) -> list[str]:
    """Preserve order, drop repeats.

    Reasons are gathered from several models that legitimately observe the
    same property, and a list that says "no shell present" twice reads as
    sloppy rather than thorough.
    """
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
